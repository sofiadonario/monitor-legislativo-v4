"""
Hybrid search service combining LexML API with CSV fallback
Implements circuit breaker pattern for seamless data source switching
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
import asyncio

from ..models.lexml_models import (
    LexMLSearchRequest, LexMLSearchResponse, LexMLDocument,
    DataSource, APIHealthStatus
)
from ..services.lexml_client import LexMLClient, LexMLAPIError
from ..services.fallback_service import CSVFallbackService
from ..services.cache_service import CacheService

logger = logging.getLogger(__name__)


class HybridSearchService:
    """
    Hybrid search service that intelligently routes between LexML API and CSV fallback
    Provides unified interface with automatic failover
    """
    
    def __init__(self, cache_service: Optional[CacheService] = None):
        self.lexml_client = LexMLClient()
        self.fallback_service = CSVFallbackService()
        self.cache_service = cache_service
        
        # Service state
        self.api_healthy = True
        self.fallback_loaded = False
        self.last_health_check = datetime.now()
        self.health_check_interval = 300  # 5 minutes
        
        # Statistics
        self.stats = {
            'total_searches': 0,
            'api_searches': 0,
            'fallback_searches': 0,
            'cache_hits': 0,
            'api_failures': 0,
            'fallback_failures': 0
        }
    
    async def initialize(self):
        """Initialize the hybrid service"""
        try:
            # Initialize cache
            if self.cache_service:
                await self.cache_service.initialize()
            
            # Load fallback data
            await self.fallback_service.load_documents()
            self.fallback_loaded = True
            logger.info("Hybrid search service initialized")
            
        except Exception as e:
            logger.error(f"Hybrid service initialization error: {e}")
            raise
    
    async def search(self, request: LexMLSearchRequest) -> LexMLSearchResponse:
        """
        Perform hybrid search with automatic failover
        """
        self.stats['total_searches'] += 1
        start_time = datetime.now()
        
        # Check cache first
        if self.cache_service:
            cached_result = await self._try_cache(request)
            if cached_result:
                self.stats['cache_hits'] += 1
                logger.debug("Search served from cache")
                return cached_result
        
        # Try API first if healthy
        if await self._should_try_api():
            try:
                async with self.lexml_client:
                    response = await self.lexml_client.search(request)
                
                self.stats['api_searches'] += 1
                self.api_healthy = True
                
                # Cache successful API response
                if self.cache_service and response.documents:
                    await self._cache_response(request, response)
                
                logger.info(f"Search completed via LexML API: {len(response.documents)} documents")
                return response
                
            except LexMLAPIError as e:
                self.stats['api_failures'] += 1
                self.api_healthy = False
                logger.warning(f"LexML API failed, falling back to CSV: {e}")
                
                # Fall through to CSV fallback
        
        # Use CSV fallback
        try:
            response = await self.fallback_service.search(request)
            self.stats['fallback_searches'] += 1
            
            # Mark as fallback data
            response.data_source = DataSource.CSV_FALLBACK
            response.api_status = "fallback"
            
            # Cache fallback response (shorter TTL)
            if self.cache_service and response.documents:
                await self._cache_response(request, response, ttl=1800)  # 30 minutes
            
            logger.info(f"Search completed via CSV fallback: {len(response.documents)} documents")
            return response
            
        except Exception as e:
            self.stats['fallback_failures'] += 1
            logger.error(f"Both API and fallback failed: {e}")
            
            # Return empty response with error status
            search_time = (datetime.now() - start_time).total_seconds() * 1000
            return LexMLSearchResponse(
                documents=[],
                total_found=0,
                start_record=request.start_record,
                records_returned=0,
                search_time_ms=search_time,
                data_source=DataSource.CSV_FALLBACK,
                cache_hit=False,
                api_status="error"
            )
    
    async def get_document_content(self, urn: str) -> Optional[Dict[str, Any]]:
        """
        Get full document content with fallover
        """
        # Check cache first
        if self.cache_service:
            cache_key = f"document_content:{urn}"
            cached_content = await self.cache_service.get(cache_key)
            if cached_content:
                return {
                    "urn": urn,
                    "content": cached_content,
                    "data_source": "cached",
                    "retrieved_at": datetime.now().isoformat()
                }
        
        # Try to get document metadata from API or fallback
        search_request = LexMLSearchRequest(
            cql_query=f'urn exact "{urn}"',
            max_records=1
        )
        
        search_response = await self.search(search_request)
        
        if not search_response.documents:
            return None
        
        document = search_response.documents[0]
        
        # For CSV fallback, we have limited content
        if search_response.data_source == DataSource.CSV_FALLBACK:
            content = {
                "urn": urn,
                "metadata": document.metadata.dict(),
                "data_source": "csv_fallback",
                "retrieved_at": datetime.now().isoformat(),
                "note": "Full text content not available in fallback mode"
            }
        else:
            # For API data, we could fetch full content (would need implementation)
            content = {
                "urn": urn,
                "metadata": document.metadata.dict(),
                "data_source": "api",
                "retrieved_at": datetime.now().isoformat(),
                "full_text_url": str(document.metadata.identifier)
            }
        
        # Cache the content
        if self.cache_service:
            cache_key = f"document_content:{urn}"
            await self.cache_service.set(cache_key, content, ttl=86400)  # 24 hours
        
        return content
    
    async def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status
        """
        api_health = None
        
        # Check API health if it's time
        if await self._should_check_api_health():
            try:
                async with self.lexml_client:
                    api_health = await self.lexml_client.get_health_status()
                self.api_healthy = api_health.is_healthy
                self.last_health_check = datetime.now()
            except Exception as e:
                logger.warning(f"API health check failed: {e}")
                self.api_healthy = False
                api_health = APIHealthStatus(
                    is_healthy=False,
                    error_message=str(e)
                )
        
        # Get fallback stats
        fallback_stats = self.fallback_service.get_stats()
        
        # Get cache stats
        cache_stats = None
        if self.cache_service:
            cache_stats = await self.cache_service.get_stats()
        
        return {
            "overall_health": self.api_healthy or self.fallback_loaded,
            "api_health": api_health.dict() if api_health else {"status": "not_checked"},
            "fallback_health": {
                "loaded": self.fallback_loaded,
                "document_count": fallback_stats.get('document_count', 0)
            },
            "cache_health": cache_stats,
            "service_stats": self.stats,
            "last_health_check": self.last_health_check.isoformat(),
            "recommended_source": "api" if self.api_healthy else "fallback"
        }
    
    async def get_suggestions(self, term: str, max_suggestions: int = 10) -> List[str]:
        """
        Get search suggestions from available sources
        """
        suggestions = []
        
        # Try API suggestions first (if healthy)
        if self.api_healthy:
            try:
                from ..services.cql_builder import CQLQueryBuilder
                builder = CQLQueryBuilder()
                api_suggestions = builder.build_suggestion_queries(term)
                suggestions.extend(api_suggestions[:max_suggestions//2])
            except Exception as e:
                logger.warning(f"API suggestions failed: {e}")
        
        # Add fallback suggestions
        if self.fallback_loaded:
            try:
                # Generate suggestions from CSV data
                fallback_suggestions = await self._get_fallback_suggestions(term)
                suggestions.extend(fallback_suggestions[:max_suggestions//2])
            except Exception as e:
                logger.warning(f"Fallback suggestions failed: {e}")
        
        return suggestions[:max_suggestions]
    
    async def _should_try_api(self) -> bool:
        """Determine if we should try the API"""
        # Always try if we think it's healthy
        if self.api_healthy:
            return True
        
        # Periodically try even if unhealthy (circuit breaker recovery)
        if await self._should_check_api_health():
            return True
        
        return False
    
    async def _should_check_api_health(self) -> bool:
        """Determine if we should check API health"""
        time_since_check = (datetime.now() - self.last_health_check).total_seconds()
        return time_since_check > self.health_check_interval
    
    async def _try_cache(self, request: LexMLSearchRequest) -> Optional[LexMLSearchResponse]:
        """Try to get result from cache"""
        if not self.cache_service:
            return None
        
        try:
            # Generate cache key from request
            cache_key = f"search:{hash(str(request.dict()))}"
            cached_result = await self.cache_service.get(cache_key)
            
            if cached_result:
                # Ensure it's a proper response object
                if isinstance(cached_result, dict):
                    cached_result['cache_hit'] = True
                    return LexMLSearchResponse(**cached_result)
                elif hasattr(cached_result, 'cache_hit'):
                    cached_result.cache_hit = True
                    return cached_result
            
            return None
            
        except Exception as e:
            logger.warning(f"Cache retrieval error: {e}")
            return None
    
    async def _cache_response(
        self, 
        request: LexMLSearchRequest, 
        response: LexMLSearchResponse, 
        ttl: int = 3600
    ):
        """Cache search response"""
        if not self.cache_service:
            return
        
        try:
            cache_key = f"search:{hash(str(request.dict()))}"
            await self.cache_service.set(cache_key, response.dict(), ttl=ttl)
        except Exception as e:
            logger.warning(f"Cache storage error: {e}")
    
    async def _get_fallback_suggestions(self, term: str) -> List[str]:
        """Generate suggestions from CSV data"""
        suggestions = []
        
        if not self.fallback_loaded:
            return suggestions
        
        try:
            # Get unique titles and subjects that match the term
            term_lower = term.lower()
            
            for doc in self.fallback_service.documents[:100]:  # Limit search
                # Check title
                if term_lower in doc.metadata.title.lower():
                    suggestions.append(doc.metadata.title)
                
                # Check subjects
                for subject in doc.metadata.subject:
                    if term_lower in subject.lower():
                        suggestions.append(subject)
                
                if len(suggestions) >= 20:  # Collect enough candidates
                    break
            
            # Remove duplicates and sort by relevance
            unique_suggestions = list(set(suggestions))
            unique_suggestions.sort(key=lambda x: x.lower().find(term_lower))
            
            return unique_suggestions[:10]
            
        except Exception as e:
            logger.warning(f"Fallback suggestions error: {e}")
            return []
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get detailed service statistics"""
        total_searches = max(self.stats['total_searches'], 1)
        
        return {
            **self.stats,
            'api_success_rate': (
                (self.stats['api_searches'] / total_searches) * 100
                if total_searches > 0 else 0
            ),
            'fallback_usage_rate': (
                (self.stats['fallback_searches'] / total_searches) * 100
                if total_searches > 0 else 0
            ),
            'cache_hit_rate': (
                (self.stats['cache_hits'] / total_searches) * 100
                if total_searches > 0 else 0
            ),
            'current_status': {
                'api_healthy': self.api_healthy,
                'fallback_loaded': self.fallback_loaded,
                'primary_source': 'api' if self.api_healthy else 'fallback'
            }
        }


# Global service instance
_hybrid_service: Optional[HybridSearchService] = None


async def get_hybrid_service() -> HybridSearchService:
    """Get or create global hybrid service instance"""
    global _hybrid_service
    if _hybrid_service is None:
        from .cache_service import get_cache_service
        cache = await get_cache_service()
        _hybrid_service = HybridSearchService(cache)
        await _hybrid_service.initialize()
    return _hybrid_service