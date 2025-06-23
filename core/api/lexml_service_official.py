"""
LexML Integration Service - Official Implementation
=================================================

Official LexML Brasil integration service using SRU protocol and proper schemas.
Implements three-tier fallback architecture with circuit breaker pattern.

Tier 1: Official LexML Brasil SRU API
Tier 2: Regional government APIs (Câmara, Senado, etc.)
Tier 3: Local CSV dataset (889 documents)

Features:
- Official SRU protocol implementation
- SKOS vocabulary expansion
- Circuit breaker pattern
- Academic metadata and citations
- Three-tier fallback with automatic failover
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import sys
import time

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .lexml_official_client import LexMLOfficialClient, LexMLDocument, LexMLSearchResponse
from ..models.lexml_official_models import (
    LexMLSearchRequest, CQLQueryBuilder, CircuitBreakerState, APIHealthStatus
)
from ..models.models import SearchResult, DataSource, Proposition

try:
    from core.lexml.vocabulary_manager import SKOSVocabularyManager
    VOCABULARY_AVAILABLE = True
except ImportError:
    print("Warning: SKOS Vocabulary Manager not available - using basic mode")
    VOCABULARY_AVAILABLE = False

try:
    from core.config.config import Config
except ImportError:
    # Simple fallback config
    class Config:
        pass

logger = logging.getLogger(__name__)

class LexMLOfficialSearchService:
    """
    Official LexML Brasil search service with three-tier fallback architecture.
    
    Implements proper SRU protocol integration with circuit breaker pattern
    and automatic failover to regional APIs and local data.
    """
    
    def __init__(self, config=None, session=None):
        """Initialize LexML search service."""
        self.config = config or Config()
        self.official_client = LexMLOfficialClient(session=session)
        self.vocabulary_manager = None
        self.circuit_breaker = CircuitBreakerState()
        self.session_cache = {}
        self.initialized = False
        
        # Performance metrics
        self.request_count = 0
        self.success_count = 0
        self.fallback_count = 0
        
        logger.info("LexML Official Search Service initialized with SRU client")
    
    async def initialize(self) -> bool:
        """
        Initialize vocabulary manager and check LexML connectivity.
        
        Returns:
            True if initialization successful, False otherwise
        """
        if self.initialized:
            return True
        
        try:
            logger.info("Initializing LexML official service...")
            
            # Initialize vocabulary manager if available
            if VOCABULARY_AVAILABLE:
                try:
                    self.vocabulary_manager = SKOSVocabularyManager()
                    # Load essential vocabularies for transport research
                    essential_vocabs = ['autoridade', 'evento', 'tipo_documento']
                    
                    async with self.vocabulary_manager as vm:
                        for vocab_name in essential_vocabs:
                            try:
                                await vm.load_vocabulary(vocab_name)
                                logger.info(f"Loaded vocabulary: {vocab_name}")
                            except Exception as e:
                                logger.warning(f"Could not load vocabulary {vocab_name}: {e}")
                    
                    logger.info("Vocabulary system initialized")
                except Exception as e:
                    logger.warning(f"Vocabulary system failed to initialize: {e}")
                    self.vocabulary_manager = None
            
            # Test LexML connectivity
            try:
                health_ok = await self.official_client.health_check()
                if health_ok:
                    logger.info("LexML Brasil SRU endpoint is accessible")
                else:
                    logger.warning("LexML Brasil SRU endpoint health check failed")
            except Exception as e:
                logger.warning(f"LexML connectivity test failed: {e}")
            
            self.initialized = True
            logger.info("LexML Official Search Service initialization complete")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize LexML Official Search Service: {e}")
            self.initialized = True  # Continue in degraded mode
            return False
    
    async def search(self, query: str, filters: Dict[str, Any] = None) -> SearchResult:
        """
        Perform three-tier search with official LexML Brasil integration.
        
        Args:
            query: Search query string
            filters: Optional search filters
            
        Returns:
            SearchResult with enhanced propositions
        """
        if not self.initialized:
            await self.initialize()
        
        self.request_count += 1
        start_time = time.time()
        
        try:
            logger.info(f"Starting three-tier search for: '{query}'")
            
            # Tier 1: Official LexML Brasil SRU API
            try:
                if not self.circuit_breaker.is_open:
                    result = await self._search_tier1_official_lexml(query, filters)
                    if result and result.total_count > 0:
                        self.success_count += 1
                        self._reset_circuit_breaker()
                        logger.info(f"Tier 1 (Official LexML) success: {result.total_count} documents")
                        return result
                    else:
                        logger.info("Tier 1 (Official LexML) returned no results, trying Tier 2")
                else:
                    logger.warning("Circuit breaker open, skipping Tier 1")
            except Exception as e:
                logger.warning(f"Tier 1 (Official LexML) failed: {e}")
                self._handle_circuit_breaker_failure()
            
            # Tier 2: Regional APIs (existing implementation)
            try:
                result = await self._search_tier2_regional_apis(query, filters)
                if result and result.total_count > 0:
                    self.fallback_count += 1
                    logger.info(f"Tier 2 (Regional APIs) success: {result.total_count} documents")
                    return result
                else:
                    logger.info("Tier 2 (Regional APIs) returned no results, trying Tier 3")
            except Exception as e:
                logger.warning(f"Tier 2 (Regional APIs) failed: {e}")
            
            # Tier 3: Local CSV dataset (889 documents)
            try:
                result = await self._search_tier3_local_data(query, filters)
                self.fallback_count += 1
                logger.info(f"Tier 3 (Local Data) success: {result.total_count} documents")
                return result
            except Exception as e:
                logger.error(f"All tiers failed. Tier 3 error: {e}")
                return self._create_empty_result(query, filters, str(e))
            
        except Exception as e:
            logger.error(f"Search failed completely: {e}")
            return self._create_empty_result(query, filters, str(e))
        finally:
            response_time = int((time.time() - start_time) * 1000)
            logger.info(f"Search completed in {response_time}ms")
    
    async def _search_tier1_official_lexml(self, query: str, filters: Dict[str, Any] = None) -> Optional[SearchResult]:
        """
        Tier 1: Search using official LexML Brasil SRU API
        """
        try:
            # Expand search terms using vocabulary if available
            expanded_terms = await self._expand_search_terms(query)
            logger.info(f"Expanded '{query}' to {len(expanded_terms)} terms")
            
            # Build search request
            search_request = LexMLSearchRequest(
                query=query,
                terms=expanded_terms,
                autoridade=filters.get('autoridade') if filters else None,
                evento=filters.get('evento') if filters else None,
                date_from=filters.get('start_date') if filters else None,
                date_to=filters.get('end_date') if filters else None,
                max_records=50,
                use_vocabulary_expansion=True
            )
            
            # Build CQL query optimized for transport
            cql_query = CQLQueryBuilder.build_transport_query(expanded_terms, filters)
            logger.debug(f"CQL Query: {cql_query}")
            
            # Execute search via official SRU client
            lexml_response = await self.official_client.search(
                query=cql_query,
                max_records=search_request.max_records,
                start_record=search_request.start_record
            )
            
            # Enhance documents with vocabulary metadata
            enhanced_docs = []
            for doc in lexml_response.documents:
                enhanced_doc = await self._enhance_document_with_vocabulary(doc, expanded_terms)
                enhanced_docs.append(enhanced_doc)
            
            # Update response
            lexml_response.documents = enhanced_docs
            lexml_response.vocabulary_expanded = len(expanded_terms) > 1
            lexml_response.expanded_terms = expanded_terms
            
            # Convert to SearchResult
            result = lexml_response.to_search_result(query, filters)
            
            # Add tier information
            result.metadata['search_tier'] = 'tier1_official_lexml'
            result.metadata['sru_protocol'] = True
            result.metadata['vocabulary_enhanced'] = len(expanded_terms) > 1
            
            return result
            
        except Exception as e:
            logger.error(f"Tier 1 search failed: {e}")
            raise
    
    async def _search_tier2_regional_apis(self, query: str, filters: Dict[str, Any] = None) -> Optional[SearchResult]:
        """
        Tier 2: Search using existing regional APIs (Câmara, Senado, etc.)
        Temporarily bypassed to focus on Tier 3 local data
        """
        try:
            logger.info("Tier 2 (Regional APIs) temporarily bypassed - proceeding to Tier 3")
            # Return None to proceed to Tier 3
            return None
            
        except Exception as e:
            logger.error(f"Tier 2 search failed: {e}")
            return None
    
    async def _search_tier3_local_data(self, query: str, filters: Dict[str, Any] = None) -> SearchResult:
        """
        Tier 3: Search using local CSV dataset (889 documents)
        """
        try:
            # Load local data with multiple path attempts
            realLegislativeData = []
            
            # Try multiple import methods
            try:
                # Method 1: Direct import
                sys.path.append(str(Path(__file__).parent.parent.parent / 'src' / 'data'))
                from real_legislative_data import realLegislativeData
                logger.info(f"Tier 3: Loaded {len(realLegislativeData)} documents via direct import")
            except ImportError:
                # Method 2: Load CSV directly
                import csv
                csv_paths = [
                    Path(__file__).parent.parent.parent / 'public' / 'lexml_transport_results_20250606_123100.csv',
                    Path(__file__).parent.parent.parent / 'dist' / 'lexml_transport_results_20250606_123100.csv',
                    Path('/app/public/lexml_transport_results_20250606_123100.csv'),  # Railway path
                ]
                
                for csv_path in csv_paths:
                    if csv_path.exists():
                        logger.info(f"Tier 3: Loading CSV from {csv_path}")
                        with open(csv_path, 'r', encoding='utf-8-sig') as f:
                            reader = csv.DictReader(f)
                            csv_data = []
                            for row in reader:
                                doc = {
                                    'id': row['urn'],
                                    'title': row['title'],
                                    'url': row['url'],
                                    'summary': f'Documento relacionado a {row["search_term"]}',
                                    'type': 'lei',  # Default type
                                    'date': '2023-01-01',  # Default date
                                    'chamber': 'Federal',
                                    'state': 'BR',
                                    'keywords': [row['search_term']]
                                }
                                csv_data.append(doc)
                        realLegislativeData.extend(csv_data)
                        logger.info(f"Tier 3: Loaded {len(csv_data)} documents from CSV")
                        break
                else:
                    logger.error("Tier 3: No CSV file found in any location")
            
            if not realLegislativeData:
                logger.warning("Tier 3: No legislative data available, returning empty result")
                return SearchResult(
                    query=query,
                    filters=filters or {},
                    propositions=[],
                    total_count=0,
                    source=DataSource.LEXML,
                    metadata={
                        'search_tier': 'tier3_local_data',
                        'error': 'No local data available'
                    }
                )
            
            # Expand search terms
            expanded_terms = await self._expand_search_terms(query)
            
            # Search through local data
            matching_docs = []
            for doc in realLegislativeData:
                if self._document_matches_search(doc, expanded_terms):
                    # Convert to LexML format
                    lexml_doc = self._convert_local_doc_to_lexml(doc, query)
                    matching_docs.append(lexml_doc)
            
            # Convert to propositions
            propositions = [doc.to_proposition() for doc in matching_docs]
            
            # Create SearchResult
            result = SearchResult(
                query=query,
                filters=filters or {},
                propositions=propositions,
                total_count=len(propositions),
                source=DataSource.LEXML,
                metadata={
                    'search_tier': 'tier3_local_data',
                    'fallback_reason': 'tier1_and_tier2_unavailable',
                    'local_dataset_size': len(realLegislativeData),
                    'vocabulary_enhanced': len(expanded_terms) > 1,
                    'expanded_terms': expanded_terms
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Tier 3 search failed: {e}")
            raise
    
    async def _expand_search_terms(self, query: str) -> List[str]:
        """Expand search terms using SKOS vocabularies"""
        expanded_terms = [query]
        
        try:
            if self.vocabulary_manager:
                # Use vocabulary expansion
                vocab_terms = self.vocabulary_manager.expand_term(query)
                expanded_terms.extend(vocab_terms)
            
            # Add transport-specific expansions
            transport_expansions = self._get_transport_specific_expansions(query)
            expanded_terms.extend(transport_expansions)
            
            # Remove duplicates and return
            return list(set(term.strip() for term in expanded_terms if term.strip()))
            
        except Exception as e:
            logger.warning(f"Term expansion failed for '{query}': {e}")
            return [query]
    
    def _get_transport_specific_expansions(self, query: str) -> List[str]:
        """Get transport-specific term expansions"""
        query_lower = query.lower()
        expansions = []
        
        transport_mappings = {
            'transporte': ['logística', 'mobilidade', 'modal', 'frete'],
            'carga': ['mercadoria', 'commodity', 'produto'],
            'rodoviário': ['BR-', 'rodovia', 'estrada'],
            'caminhão': ['veículo comercial', 'veículo pesado'],
            'sustentável': ['verde', 'limpo', 'ecológico'],
            'combustível': ['energia', 'diesel', 'biodiesel', 'etanol'],
            'licenciamento': ['licença', 'autorização', 'permissão']
        }
        
        for key, values in transport_mappings.items():
            if key in query_lower:
                expansions.extend(values)
        
        return expansions
    
    async def _enhance_document_with_vocabulary(self, doc: LexMLDocument, expanded_terms: List[str]) -> LexMLDocument:
        """Enhance document with vocabulary metadata"""
        try:
            if self.vocabulary_manager:
                # Add vocabulary-enhanced metadata
                doc.metadata = type('Metadata', (), {
                    'vocabulario_expandido': expanded_terms,
                    'termos_relacionados': [],
                    'citacao_academica': self._generate_academic_citation(doc),
                    'nivel_relevancia': self._calculate_relevance(doc, expanded_terms),
                    'fonte_original': 'LexML Brasil'
                })()
            
            return doc
            
        except Exception as e:
            logger.warning(f"Document enhancement failed: {e}")
            return doc
    
    def _document_matches_search(self, doc: Dict[str, Any], search_terms: List[str]) -> bool:
        """Check if document matches search terms"""
        searchable_text = f"{doc.get('title', '')} {doc.get('summary', '')}".lower()
        
        for term in search_terms:
            if term.lower() in searchable_text:
                return True
        
        # Check keywords
        keywords = doc.get('keywords', [])
        for keyword in keywords:
            for term in search_terms:
                if term.lower() in keyword.lower():
                    return True
        
        return False
    
    def _convert_local_doc_to_lexml(self, doc: Dict[str, Any], query: str) -> LexMLDocument:
        """Convert local document to LexML format"""
        return LexMLDocument(
            urn=doc.get('id', ''),
            title=doc.get('title', ''),
            autoridade=doc.get('chamber', 'br'),
            evento='publicacao',
            localidade=doc.get('state', 'BR'),
            data_evento=doc.get('date', datetime.now().strftime('%Y-%m-%d')),
            tipo_documento=doc.get('type', 'outros').lower(),
            texto_integral_url=doc.get('url', ''),
            resumo=doc.get('summary', ''),
            palavras_chave=doc.get('keywords', [])
        )
    
    def _generate_academic_citation(self, doc: LexMLDocument) -> str:
        """Generate academic citation for document"""
        try:
            title = doc.title
            autoridade = doc.autoridade
            data = doc.data_evento
            url = doc.texto_integral_url or f"https://www.lexml.gov.br/urn/{doc.urn}"
            
            return f"{autoridade.upper()}. {title}. {data}. Disponível em: {url}. Acesso em: {datetime.now().strftime('%d/%m/%Y')}."
        except:
            return f"{doc.title}. Disponível em: LexML Brasil. Acesso em: {datetime.now().strftime('%d/%m/%Y')}."
    
    def _calculate_relevance(self, doc: LexMLDocument, search_terms: List[str]) -> float:
        """Calculate document relevance score"""
        try:
            text = f"{doc.title} {doc.resumo or ''}".lower()
            matches = sum(1 for term in search_terms if term.lower() in text)
            return min(matches / len(search_terms), 1.0) if search_terms else 0.0
        except:
            return 0.5
    
    def _handle_circuit_breaker_failure(self):
        """Handle circuit breaker failure logic"""
        self.circuit_breaker.failure_count += 1
        self.circuit_breaker.last_failure_time = datetime.now()
        
        if self.circuit_breaker.failure_count >= 3:
            self.circuit_breaker.is_open = True
            logger.warning("Circuit breaker opened due to repeated failures")
    
    def _reset_circuit_breaker(self):
        """Reset circuit breaker on success"""
        self.circuit_breaker.failure_count = 0
        self.circuit_breaker.is_open = False
        self.circuit_breaker.last_success_time = datetime.now()
    
    def _create_empty_result(self, query: str, filters: Dict[str, Any], error: str) -> SearchResult:
        """Create empty search result with error"""
        return SearchResult(
            query=query,
            filters=filters or {},
            propositions=[],
            total_count=0,
            source=DataSource.LEXML,
            error=error,
            metadata={
                'search_tier': 'all_tiers_failed',
                'error_details': error
            }
        )
    
    def get_vocabulary_stats(self) -> Dict[str, Any]:
        """Get vocabulary statistics"""
        if self.vocabulary_manager:
            return {
                'status': 'active',
                'mode': 'enhanced' if self.vocabulary_manager else 'basic',
                'expansions_available': True,
                'transport_domain_active': True
            }
        return {
            'status': 'inactive',
            'mode': 'basic',
            'expansions_available': False,
            'transport_domain_active': False
        }
    
    async def get_health_status(self) -> APIHealthStatus:
        """Get service health status"""
        try:
            start_time = time.time()
            is_healthy = await self.official_client.health_check()
            response_time = int((time.time() - start_time) * 1000)
            
            return APIHealthStatus(
                is_healthy=is_healthy,
                last_check=datetime.now(),
                response_time_ms=response_time,
                circuit_breaker_state=self.circuit_breaker
            )
        except Exception as e:
            return APIHealthStatus(
                is_healthy=False,
                last_check=datetime.now(),
                error_message=str(e),
                circuit_breaker_state=self.circuit_breaker
            )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        success_rate = (self.success_count / self.request_count * 100) if self.request_count > 0 else 0
        fallback_rate = (self.fallback_count / self.request_count * 100) if self.request_count > 0 else 0
        
        return {
            'total_requests': self.request_count,
            'successful_requests': self.success_count,
            'fallback_requests': self.fallback_count,
            'success_rate_percent': round(success_rate, 2),
            'fallback_rate_percent': round(fallback_rate, 2),
            'circuit_breaker_open': self.circuit_breaker.is_open,
            'vocabulary_enabled': VOCABULARY_AVAILABLE
        }
    
    async def close(self):
        """Cleanup resources"""
        if self.official_client:
            await self.official_client.close()


# Alias for backward compatibility
LexMLSearchService = LexMLOfficialSearchService