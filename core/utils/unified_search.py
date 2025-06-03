"""
Unified Search System
Implements search optimization recommendations from analysis
"""

import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import json
import logging

from ..models.models import SearchResult, Proposition, DataSource
from .smart_cache import cached as smart_cache
from .monitoring_dashboard import monitoring_dashboard


@dataclass
class SearchIndex:
    """Search index entry"""
    proposition_id: str
    source: str
    title: str
    summary: str
    keywords: Set[str]
    date: datetime
    relevance_score: float = 0.0


class UnifiedSearch:
    """
    Unified search system with indexing and optimization
    Implements recommendations for search optimization
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # In-memory search index (should be replaced with ElasticSearch in production)
        self.search_index: Dict[str, SearchIndex] = {}
        
        # Pre-computed common queries
        self.common_queries = [
            "energia", "saúde", "educação", "transporte", "telecomunicações",
            "meio ambiente", "infraestrutura", "segurança", "economia", "tributos"
        ]
        
        # Query performance tracking
        self.query_performance: Dict[str, Dict[str, float]] = {}
        
        # Search optimization settings
        self.parallel_batch_size = 5
        self.index_update_interval = 3600  # 1 hour
        
    async def search_optimized(self, 
                             query: str, 
                             sources: List[str],
                             filters: Dict[str, Any]) -> List[SearchResult]:
        """
        Optimized search across multiple sources
        Implements parallel processing and caching strategies
        """
        start_time = datetime.now()
        
        # Check if this is a common query
        is_common = query.lower() in self.common_queries
        
        # Generate cache key
        cache_key = self._generate_cache_key(query, sources, filters)
        
        # Try cache first (longer TTL for common queries)
        cache_ttl = 7200 if is_common else 3600  # 2 hours vs 1 hour
        cached_results = await smart_cache.get(cache_key, source="unified_search")
        
        if cached_results:
            self.logger.info(f"Cache hit for query: {query}")
            return cached_results
        
        # Group sources by type for optimal processing
        api_sources = []
        scraper_sources = []
        
        for source in sources:
            source_type = monitoring_dashboard.sources_config.get(source)
            if source_type and source_type.value == "legislative_api":
                api_sources.append(source)
            else:
                scraper_sources.append(source)
        
        # Process in optimal order
        results = await self._process_sources_optimized(
            query, filters, api_sources, scraper_sources
        )
        
        # Update search index
        await self._update_search_index(results)
        
        # Cache results
        await smart_cache.set(cache_key, results, ttl=cache_ttl, source="unified_search")
        
        # Track performance
        self._track_query_performance(query, sources, datetime.now() - start_time)
        
        return results
    
    async def _process_sources_optimized(self,
                                       query: str,
                                       filters: Dict[str, Any],
                                       api_sources: List[str],
                                       scraper_sources: List[str]) -> List[SearchResult]:
        """Process sources in optimal order with parallelization"""
        from ..api.api_service import APIService
        
        api_service = APIService()
        all_results = []
        
        # Process fast API sources first
        if api_sources:
            api_tasks = []
            for source in api_sources:
                # Check if source is healthy before querying
                status = await monitoring_dashboard.check_source_health(source)
                if status.circuit_breaker_state != "open":
                    api_tasks.append(
                        api_service.search_single_source(source, query, filters)
                    )
                else:
                    self.logger.warning(f"Skipping {source} - circuit breaker open")
            
            if api_tasks:
                api_results = await asyncio.gather(*api_tasks, return_exceptions=True)
                all_results.extend([r for r in api_results if isinstance(r, SearchResult)])
        
        # Process scrapers in batches to avoid overwhelming
        if scraper_sources:
            for i in range(0, len(scraper_sources), self.parallel_batch_size):
                batch = scraper_sources[i:i + self.parallel_batch_size]
                batch_tasks = []
                
                for source in batch:
                    # Check health and circuit breaker
                    status = await monitoring_dashboard.check_source_health(source)
                    if status.circuit_breaker_state != "open":
                        batch_tasks.append(
                            api_service.search_single_source(source, query, filters)
                        )
                
                if batch_tasks:
                    batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                    all_results.extend([r for r in batch_results if isinstance(r, SearchResult)])
                
                # Small delay between batches
                if i + self.parallel_batch_size < len(scraper_sources):
                    await asyncio.sleep(0.5)
        
        return all_results
    
    async def pre_index_common_queries(self):
        """Pre-index common queries for faster retrieval"""
        self.logger.info("Starting pre-indexing of common queries")
        
        from ..api.api_service import APIService
        api_service = APIService()
        
        # Get date range for indexing
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        filters = {
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d")
        }
        
        # Get healthy sources
        all_sources = list(monitoring_dashboard.sources_config.keys())
        healthy_sources = []
        
        for source in all_sources:
            status = await monitoring_dashboard.check_source_health(source)
            if status.status.value == "healthy":
                healthy_sources.append(source)
        
        # Pre-index each common query
        for query in self.common_queries:
            try:
                self.logger.info(f"Pre-indexing query: {query}")
                
                results = await self.search_optimized(
                    query, healthy_sources[:5], filters  # Limit to 5 sources
                )
                
                # Longer cache TTL for pre-indexed queries
                cache_key = self._generate_cache_key(query, healthy_sources[:5], filters)
                await smart_cache.set(cache_key, results, ttl=14400, source="unified_search")  # 4 hours
                
                await asyncio.sleep(2)  # Rate limiting
                
            except Exception as e:
                self.logger.error(f"Failed to pre-index query {query}: {e}")
    
    async def _update_search_index(self, results: List[SearchResult]):
        """Update search index with new results"""
        for result in results:
            for prop in result.propositions:
                # Generate unique ID
                index_id = f"{result.source.value}_{prop.id}"
                
                # Extract keywords
                keywords = self._extract_keywords(prop.title + " " + prop.summary)
                
                # Create index entry
                self.search_index[index_id] = SearchIndex(
                    proposition_id=prop.id,
                    source=result.source.value,
                    title=prop.title,
                    summary=prop.summary,
                    keywords=keywords,
                    date=prop.publication_date or datetime.now()
                )
    
    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract keywords from text"""
        # Simple keyword extraction (should use NLP in production)
        stopwords = {
            "de", "a", "o", "que", "e", "do", "da", "em", "no", "na", 
            "um", "uma", "para", "com", "por", "dos", "das", "ao", "aos"
        }
        
        words = text.lower().split()
        keywords = {
            word for word in words 
            if len(word) > 3 and word not in stopwords
        }
        
        return keywords
    
    def _generate_cache_key(self, query: str, sources: List[str], filters: Dict[str, Any]) -> str:
        """Generate cache key for search"""
        key_data = {
            "query": query.lower(),
            "sources": sorted(sources),
            "filters": filters
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return f"unified_search_{hashlib.md5(key_string.encode()).hexdigest()}"
    
    def _track_query_performance(self, query: str, sources: List[str], duration: timedelta):
        """Track query performance metrics"""
        query_key = query.lower()
        
        if query_key not in self.query_performance:
            self.query_performance[query_key] = {
                "count": 0,
                "total_duration": 0,
                "avg_duration": 0,
                "sources": {}
            }
        
        perf = self.query_performance[query_key]
        perf["count"] += 1
        perf["total_duration"] += duration.total_seconds()
        perf["avg_duration"] = perf["total_duration"] / perf["count"]
        
        # Track per-source performance
        for source in sources:
            if source not in perf["sources"]:
                perf["sources"][source] = {"count": 0}
            perf["sources"][source]["count"] += 1
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get search performance report"""
        return {
            "total_queries": sum(p["count"] for p in self.query_performance.values()),
            "unique_queries": len(self.query_performance),
            "top_queries": self._get_top_queries(10),
            "slowest_queries": self._get_slowest_queries(5),
            "cache_stats": smart_cache.get_stats()
        }
    
    def _get_top_queries(self, limit: int) -> List[Dict[str, Any]]:
        """Get most frequent queries"""
        sorted_queries = sorted(
            self.query_performance.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )
        
        return [
            {
                "query": query,
                "count": data["count"],
                "avg_duration": data["avg_duration"]
            }
            for query, data in sorted_queries[:limit]
        ]
    
    def _get_slowest_queries(self, limit: int) -> List[Dict[str, Any]]:
        """Get slowest queries"""
        sorted_queries = sorted(
            self.query_performance.items(),
            key=lambda x: x[1]["avg_duration"],
            reverse=True
        )
        
        return [
            {
                "query": query,
                "avg_duration": data["avg_duration"],
                "count": data["count"]
            }
            for query, data in sorted_queries[:limit]
        ]
    
    async def search_with_relevance(self, 
                                  query: str, 
                                  sources: List[str],
                                  filters: Dict[str, Any]) -> List[SearchResult]:
        """
        Search with relevance scoring
        Future enhancement: integrate with ElasticSearch
        """
        # Get basic results
        results = await self.search_optimized(query, sources, filters)
        
        # Score propositions by relevance
        query_terms = set(query.lower().split())
        
        for result in results:
            for prop in result.propositions:
                # Simple relevance scoring
                title_terms = set(prop.title.lower().split())
                summary_terms = set(prop.summary.lower().split())
                
                title_matches = len(query_terms & title_terms)
                summary_matches = len(query_terms & summary_terms)
                
                # Calculate relevance score (0-100)
                prop.relevance_score = min(
                    100,
                    (title_matches * 20) + (summary_matches * 5)
                )
            
            # Sort by relevance
            result.propositions.sort(key=lambda p: p.relevance_score, reverse=True)
        
        return results


# Global unified search instance
unified_search = UnifiedSearch()