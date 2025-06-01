"""
Unified Search Service
Integrates Elasticsearch with database fallback and caching
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import time
import json
from dataclasses import dataclass, asdict

from .elasticsearch_service import ElasticsearchService, SearchRequest, SearchResponse
from ..database.optimization_service import DatabaseOptimizationService
from ..utils.smart_cache import get_cache, CacheKeyBuilder, cached
from ..utils.circuit_breaker import CircuitBreaker
from ..models.models import Proposition, SearchResult, SearchFilters, DataSource

logger = logging.getLogger(__name__)

@dataclass
class UnifiedSearchRequest:
    """Unified search request across all backends"""
    query: str
    filters: SearchFilters = None
    page: int = 1
    page_size: int = 25
    sort_by: str = "relevance"
    use_cache: bool = True
    prefer_elasticsearch: bool = True
    include_facets: bool = True
    highlight: bool = True
    
@dataclass 
class UnifiedSearchResponse:
    """Unified search response with metadata"""
    results: List[Proposition]
    total_count: int
    page: int
    page_size: int
    facets: Dict[str, List[Dict[str, Any]]]
    search_time_ms: int
    backend_used: str  # elasticsearch, database, cache
    from_cache: bool
    query: str
    
class UnifiedSearchService:
    """Main search service with multiple backends"""
    
    def __init__(self, 
                 elasticsearch_service: ElasticsearchService = None,
                 database_service: DatabaseOptimizationService = None):
        
        self.es_service = elasticsearch_service
        self.db_service = database_service
        self.cache = get_cache()
        
        # Circuit breakers for fault tolerance
        self.es_circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=Exception
        )
        
        # Performance tracking
        self._search_metrics = {
            'total_searches': 0,
            'cache_hits': 0,
            'es_searches': 0,
            'db_searches': 0,
            'total_time_ms': 0
        }
    
    def search(self, request: UnifiedSearchRequest) -> UnifiedSearchResponse:
        """Perform unified search across all backends"""
        
        start_time = time.time()
        self._search_metrics['total_searches'] += 1
        
        # Try cache first if enabled
        if request.use_cache:
            cached_result = self._get_cached_result(request)
            if cached_result:
                self._search_metrics['cache_hits'] += 1
                return cached_result
        
        # Try Elasticsearch if preferred and available
        if request.prefer_elasticsearch and self.es_service:
            try:
                with self.es_circuit_breaker:
                    result = self._search_elasticsearch(request)
                    if result:
                        self._search_metrics['es_searches'] += 1
                        # Cache the result
                        if request.use_cache:
                            self._cache_result(request, result)
                        return result
            except Exception as e:
                logger.warning(f"Elasticsearch search failed, falling back to database: {e}")
        
        # Fallback to database search
        result = self._search_database(request)
        self._search_metrics['db_searches'] += 1
        
        # Cache the result
        if request.use_cache:
            self._cache_result(request, result)
        
        # Update total search time
        search_time = int((time.time() - start_time) * 1000)
        self._search_metrics['total_time_ms'] += search_time
        
        return result
    
    def _get_cached_result(self, request: UnifiedSearchRequest) -> Optional[UnifiedSearchResponse]:
        """Get cached search result"""
        
        cache_key = self._build_cache_key(request)
        cached_data = self.cache.get(cache_key)
        
        if cached_data:
            try:
                # Reconstruct response from cached data
                data = json.loads(cached_data) if isinstance(cached_data, str) else cached_data
                
                # Convert dictionaries back to Proposition objects
                propositions = []
                for prop_dict in data['results']:
                    # Create Proposition from dict
                    prop = self._dict_to_proposition(prop_dict)
                    propositions.append(prop)
                
                return UnifiedSearchResponse(
                    results=propositions,
                    total_count=data['total_count'],
                    page=data['page'],
                    page_size=data['page_size'],
                    facets=data.get('facets', {}),
                    search_time_ms=0,  # Instant from cache
                    backend_used='cache',
                    from_cache=True,
                    query=data['query']
                )
            except Exception as e:
                logger.error(f"Failed to deserialize cached result: {e}")
                return None
        
        return None
    
    def _cache_result(self, request: UnifiedSearchRequest, response: UnifiedSearchResponse):
        """Cache search result"""
        
        try:
            cache_key = self._build_cache_key(request)
            
            # Convert propositions to dicts for caching
            results_dict = [prop.to_dict() for prop in response.results]
            
            cache_data = {
                'results': results_dict,
                'total_count': response.total_count,
                'page': response.page,
                'page_size': response.page_size,
                'facets': response.facets,
                'query': response.query,
                'cached_at': datetime.utcnow().isoformat()
            }
            
            # Cache for 15 minutes
            self.cache.set(cache_key, cache_data, ttl=900)
            
        except Exception as e:
            logger.error(f"Failed to cache search result: {e}")
    
    def _build_cache_key(self, request: UnifiedSearchRequest) -> str:
        """Build cache key for search request"""
        
        key_parts = {
            'query': request.query,
            'page': request.page,
            'page_size': request.page_size,
            'sort_by': request.sort_by
        }
        
        if request.filters:
            key_parts['filters'] = request.filters.to_dict()
        
        return CacheKeyBuilder.build_key("search", **key_parts)
    
    def _search_elasticsearch(self, request: UnifiedSearchRequest) -> Optional[UnifiedSearchResponse]:
        """Search using Elasticsearch"""
        
        if not self.es_service:
            return None
        
        start_time = time.time()
        
        # Convert to Elasticsearch request
        es_request = SearchRequest(
            query=request.query,
            filters=request.filters.to_dict() if request.filters else None,
            facets=['type', 'status', 'year', 'source', 'keywords'] if request.include_facets else None,
            sort_by=self._map_sort_field(request.sort_by),
            page=request.page,
            page_size=request.page_size,
            highlight=request.highlight
        )
        
        # Execute search
        es_response = self.es_service.search(es_request)
        
        # Convert results to Propositions
        propositions = []
        for result in es_response.results:
            prop = self._dict_to_proposition(result)
            propositions.append(prop)
        
        search_time = int((time.time() - start_time) * 1000)
        
        return UnifiedSearchResponse(
            results=propositions,
            total_count=es_response.total_count,
            page=es_response.page,
            page_size=es_response.page_size,
            facets=es_response.facets,
            search_time_ms=search_time,
            backend_used='elasticsearch',
            from_cache=False,
            query=es_response.query
        )
    
    def _search_database(self, request: UnifiedSearchRequest) -> UnifiedSearchResponse:
        """Search using database"""
        
        if not self.db_service:
            # Return empty result if no database service
            return UnifiedSearchResponse(
                results=[],
                total_count=0,
                page=request.page,
                page_size=request.page_size,
                facets={},
                search_time_ms=0,
                backend_used='none',
                from_cache=False,
                query=request.query
            )
        
        # Convert filters
        db_filters = {}
        if request.filters:
            if request.filters.start_date:
                db_filters['date_from'] = request.filters.start_date
            if request.filters.end_date:
                db_filters['date_to'] = request.filters.end_date
            if request.filters.types:
                db_filters['type'] = request.filters.types[0].name if len(request.filters.types) == 1 else None
            if request.filters.status:
                db_filters['status'] = request.filters.status.name
            if request.filters.sources:
                db_filters['source_id'] = None  # Would need to map source to ID
        
        # Calculate offset
        offset = (request.page - 1) * request.page_size
        
        # Execute database search
        propositions, search_time = self.db_service.optimize_proposition_search(
            query=request.query,
            filters=db_filters,
            limit=request.page_size,
            offset=offset
        )
        
        # Convert database models to our Proposition model
        results = []
        for db_prop in propositions:
            prop = self._db_model_to_proposition(db_prop)
            results.append(prop)
        
        # Generate basic facets from results (limited compared to ES)
        facets = self._generate_facets_from_results(results) if request.include_facets else {}
        
        return UnifiedSearchResponse(
            results=results,
            total_count=len(results),  # Database doesn't return total easily
            page=request.page,
            page_size=request.page_size,
            facets=facets,
            search_time_ms=int(search_time),
            backend_used='database',
            from_cache=False,
            query=request.query
        )
    
    def _dict_to_proposition(self, data: Dict[str, Any]) -> Proposition:
        """Convert dictionary to Proposition model"""
        
        from ..models.models import Proposition, PropositionType, PropositionStatus, DataSource, Author
        
        # Convert enums
        prop_type = PropositionType[data.get('type', 'OTHER').upper().replace(' ', '_')]
        status = PropositionStatus[data.get('status', 'UNKNOWN').upper().replace(' ', '_')]
        source = DataSource[data.get('source', 'CAMARA').upper().replace(' ', '_')]
        
        # Convert authors
        authors = []
        for author_data in data.get('authors', []):
            authors.append(Author(
                name=author_data.get('name', ''),
                type=author_data.get('type', 'Unknown'),
                party=author_data.get('party'),
                state=author_data.get('state'),
                id=author_data.get('id')
            ))
        
        # Convert dates
        pub_date = data.get('publication_date')
        if isinstance(pub_date, str):
            pub_date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
        
        last_update = data.get('last_update')
        if isinstance(last_update, str):
            last_update = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
        
        return Proposition(
            id=data['id'],
            type=prop_type,
            number=data.get('number', ''),
            year=data.get('year', 0),
            title=data.get('title', ''),
            summary=data.get('summary', ''),
            source=source,
            status=status,
            url=data.get('url', ''),
            publication_date=pub_date,
            last_update=last_update,
            authors=authors,
            keywords=data.get('keywords', []),
            full_text_url=data.get('full_text_url'),
            attachments=data.get('attachments', []),
            extra_data=data.get('extra_data', {})
        )
    
    def _db_model_to_proposition(self, db_model) -> Proposition:
        """Convert database model to Proposition"""
        
        from ..models.models import Proposition, PropositionType, PropositionStatus, DataSource, Author
        
        # This would need actual mapping based on your DB model
        # Placeholder implementation
        return Proposition(
            id=db_model.id,
            type=PropositionType[db_model.type],
            number=db_model.number,
            year=db_model.year,
            title=db_model.title,
            summary=db_model.summary,
            source=DataSource.CAMARA,  # Would need proper mapping
            status=PropositionStatus[db_model.status],
            url=db_model.url,
            publication_date=db_model.publication_date,
            last_update=db_model.last_update,
            authors=[],  # Would need to load from relationship
            keywords=db_model.keywords if hasattr(db_model, 'keywords') else [],
            full_text_url=db_model.full_text_url,
            attachments=db_model.attachments if hasattr(db_model, 'attachments') else [],
            extra_data=db_model.extra_data if hasattr(db_model, 'extra_data') else {}
        )
    
    def _map_sort_field(self, sort_by: str) -> str:
        """Map sort field names between unified and ES"""
        
        mapping = {
            'relevance': '_score',
            'date': 'publication_date',
            'popularity': 'popularity_score',
            'title': 'title.keyword'
        }
        
        return mapping.get(sort_by, '_score')
    
    def _generate_facets_from_results(self, results: List[Proposition]) -> Dict[str, List[Dict[str, Any]]]:
        """Generate basic facets from search results"""
        
        facets = {
            'type': {},
            'status': {},
            'year': {},
            'source': {}
        }
        
        # Count occurrences
        for prop in results:
            # Type facet
            type_val = prop.type.value
            facets['type'][type_val] = facets['type'].get(type_val, 0) + 1
            
            # Status facet
            status_val = prop.status.value
            facets['status'][status_val] = facets['status'].get(status_val, 0) + 1
            
            # Year facet
            year_val = str(prop.year)
            facets['year'][year_val] = facets['year'].get(year_val, 0) + 1
            
            # Source facet
            source_val = prop.source.value
            facets['source'][source_val] = facets['source'].get(source_val, 0) + 1
        
        # Convert to list format
        formatted_facets = {}
        for facet_name, counts in facets.items():
            formatted_facets[facet_name] = [
                {'value': k, 'count': v}
                for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)
            ]
        
        return formatted_facets
    
    def suggest(self, prefix: str, size: int = 10) -> List[str]:
        """Get search suggestions"""
        
        if self.es_service:
            try:
                return self.es_service.suggest(prefix, size)
            except Exception as e:
                logger.warning(f"Elasticsearch suggest failed: {e}")
        
        # Fallback to simple database suggestions
        # This would need to be implemented based on your needs
        return []
    
    def find_similar(self, proposition_id: str, size: int = 10) -> List[Proposition]:
        """Find similar propositions"""
        
        if self.es_service:
            try:
                similar = self.es_service.more_like_this(proposition_id, size)
                return [self._dict_to_proposition(item) for item in similar]
            except Exception as e:
                logger.warning(f"Elasticsearch MLT failed: {e}")
        
        # Fallback to keyword-based similarity
        # This would need to be implemented
        return []
    
    def get_trending(self, days: int = 7, size: int = 10) -> List[Proposition]:
        """Get trending propositions"""
        
        # Try database first (has click data)
        if self.db_service:
            with self.db_service.get_session() as session:
                from ..database.models import OptimizedQueries
                trending = OptimizedQueries.get_trending_propositions(session, days, size)
                return [self._db_model_to_proposition(prop) for prop in trending]
        
        return []
    
    def index_proposition(self, proposition: Proposition) -> bool:
        """Index a proposition in Elasticsearch"""
        
        if self.es_service:
            try:
                prop_dict = proposition.to_dict()
                return self.es_service.index_proposition(prop_dict)
            except Exception as e:
                logger.error(f"Failed to index proposition: {e}")
        
        return False
    
    def bulk_index_propositions(self, propositions: List[Proposition]) -> Tuple[int, int]:
        """Bulk index propositions"""
        
        if self.es_service:
            try:
                prop_dicts = [prop.to_dict() for prop in propositions]
                return self.es_service.bulk_index_propositions(prop_dicts)
            except Exception as e:
                logger.error(f"Bulk indexing failed: {e}")
        
        return 0, len(propositions)
    
    def get_search_metrics(self) -> Dict[str, Any]:
        """Get search performance metrics"""
        
        metrics = self._search_metrics.copy()
        
        # Calculate averages
        if metrics['total_searches'] > 0:
            metrics['avg_search_time_ms'] = metrics['total_time_ms'] / metrics['total_searches']
            metrics['cache_hit_rate'] = (metrics['cache_hits'] / metrics['total_searches']) * 100
            metrics['es_usage_rate'] = (metrics['es_searches'] / metrics['total_searches']) * 100
            metrics['db_usage_rate'] = (metrics['db_searches'] / metrics['total_searches']) * 100
        
        # Add backend health
        if self.es_service:
            metrics['elasticsearch_health'] = self.es_service.health_check()
        
        if self.db_service:
            metrics['database_health'] = self.db_service.health_check()
        
        return metrics
    
    def optimize_search_backends(self):
        """Run optimization on all search backends"""
        
        logger.info("Starting search backend optimization...")
        
        # Optimize Elasticsearch
        if self.es_service:
            try:
                self.es_service.optimize_index()
                logger.info("Elasticsearch optimization completed")
            except Exception as e:
                logger.error(f"Elasticsearch optimization failed: {e}")
        
        # Optimize database
        if self.db_service:
            try:
                self.db_service.optimize_search_performance()
                logger.info("Database optimization completed")
            except Exception as e:
                logger.error(f"Database optimization failed: {e}")
        
        logger.info("Search backend optimization completed")

# Global unified search service
_unified_search: Optional[UnifiedSearchService] = None

def get_unified_search_service() -> UnifiedSearchService:
    """Get global unified search service"""
    global _unified_search
    if _unified_search is None:
        # Initialize with available services
        from .elasticsearch_service import get_elasticsearch_service
        from ..database.optimization_service import get_database_service
        
        _unified_search = UnifiedSearchService(
            elasticsearch_service=get_elasticsearch_service(),
            database_service=get_database_service()
        )
    
    return _unified_search

def init_unified_search_service(elasticsearch_service: ElasticsearchService = None,
                              database_service: DatabaseOptimizationService = None) -> UnifiedSearchService:
    """Initialize global unified search service"""
    global _unified_search
    _unified_search = UnifiedSearchService(elasticsearch_service, database_service)
    return _unified_search